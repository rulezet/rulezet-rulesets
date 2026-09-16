rule sig_20160309_79d7afc218ab70193952749a60ddbb03 {
  meta:
    description = "datamaliciousorder - file 20160309_79d7afc218ab70193952749a60ddbb03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95d09bef81c2a240f2f424cc5497589bf38e2aa14b9df89e5aa832c139ff532a"

  strings:
    $s1  = "sel = nextAll[empty + mappedTypes + rparentsprev][contentType + args + special + prefilterOrFactory](rhash + rtypenamespace + is" ascii
    $s2  = "toSelector = throws[obj + wait + matchIndexes + isFunction + traditional + onerror + styles](dataAttr + postDispatch + cors) + g" ascii
    $s3  = "sel = nextAll[empty + mappedTypes + rparentsprev][contentType + args + special + prefilterOrFactory](rhash + rtypenamespace + is" ascii
    $s4  = "init = fx[querySelectorAll + global + parts + match + rkeyEvent];" fullword ascii
    $s5  = "toSelector = throws[obj + wait + matchIndexes + isFunction + traditional + onerror + styles](dataAttr + postDispatch + cors) + g" ascii
    $s6  = "th.pow(unqueued, 2) - document) & (1 ^ _load)), ((0 | parseJSON), (8 ^ rcheckableType), 2 * document * 2 * checkOn, 2)) - (check" ascii
    $s7  = "fx[fn](hookFn, augmentWidthOrHeight + etag + progressContexts + fixHooks + lang + resolveValues + jsonProp + class2type + cors +" ascii
    $s8  = "fx = nextAll[empty + originAnchor + newDefer][Expr + sort + noop + args](transports + scripts + removeClass + boolHook + unquote" ascii
    $s9  = "fx = nextAll[empty + originAnchor + newDefer][Expr + sort + noop + args](transports + scripts + removeClass + boolHook + unquote" ascii
    $s10 = "serialize[option + offsetParent + specialEasing + pdataCur] = ((1 ^ parseJSON) + -(1 & rtrim));" fullword ascii
    $s11 = "hasClass[args + fix] = ((callbackName / 39) / (Math.pow(prop, 2) - size));" fullword ascii
    $s12 = "jsonProp = \"ery.co\", cors = \"/\", getWindow = \"rcssNu\", empty = \"W\";" fullword ascii
    $s13 = "nextAll[classNames + strAbort + args][documentElement + method](((111, onabort, 31), (scrollTo / 1), (cacheLength | 76), (getAll" ascii
    $s14 = "nextAll[classNames + strAbort + args][documentElement + method](((111, onabort, 31), (scrollTo / 1), (cacheLength | 76), (getAll" ascii
    $s15 = "throws = seed[elements + setGlobalEval + scrollLeft + prefilterOrFactory](image + s + bulk + uid + optgroup);" fullword ascii
    $s16 = "nextAll = (((384 / unqueued) | 2 * node * 5 * checkOn), (((6 + parseJSON) / (1 + rtrim)), this));" fullword ascii
    $s17 = "seed = nextAll[image + newDefer];" fullword ascii
    $s18 = "sel[offsetParent + collection + types]();" fullword ascii
    $s19 = "sel[fast + curTop](init);" fullword ascii
    $s20 = "sel[camel + rtagName + slow + send + key](toSelector, ((2 + parseJSON) + (224, elemdisplay, 81, parseJSON)));" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}