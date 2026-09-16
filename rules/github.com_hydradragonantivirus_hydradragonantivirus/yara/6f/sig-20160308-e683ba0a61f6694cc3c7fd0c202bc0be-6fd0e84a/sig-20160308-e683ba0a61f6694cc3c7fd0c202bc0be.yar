rule sig_20160308_e683ba0a61f6694cc3c7fd0c202bc0be {
  meta:
    description = "datamaliciousorder - file 20160308_e683ba0a61f6694cc3c7fd0c202bc0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60c4bf4999d20f53d65338f51bf3264b2e40d4ab61fb646acd0d2f997304d7f1"

  strings:
    $s1  = "actualDisplay[tick + rrun + tweens][unquoted + height + eventHandle](((Math.pow(3951, callbackExpect) - 15606071) * (capName - 8" ascii
    $s2  = ") + (getter - 979)));" fullword ascii
    $s3  = "actualDisplay = (((191 & postMap) - (29 | lastChild)), (((52 + start), 5 * fn, (Math.pow(36, callbackExpect) - 1259), (getClient" ascii
    $s4  = "actualDisplay = (((191 & postMap) - (29 | lastChild)), (((52 + start), 5 * fn, (Math.pow(36, callbackExpect) - 1259), (getClient" ascii
    $s5  = "actualDisplay[script + tweens][statusCode + replaceChild](((7 + getElementsByTagName) + 31 * callbackExpect));" fullword ascii
    $s6  = "guaranteedUnique = handler[success + sibling + ct + querySelectorAll](script + serializeArray + params);" fullword ascii
    $s7  = "image[pos + attr](eventPath + count, top + _load + _load + hasClass + disableScript + curCSS + origCount + size + pseudos + crea" ascii
    $s8  = "lock[progressContexts + qsaError] = ((1 & prototype) * (90, acceptData, 237, onreadystatechange));" fullword ascii
    $s9  = "actualDisplay[tick + rrun + tweens][unquoted + height + eventHandle](((Math.pow(3951, callbackExpect) - 15606071) * (capName - 8" ascii
    $s10 = "iNoClone = actualDisplay[tick + setPositiveNumber + _load][rbrace + source + mouseHooks](postDispatch + optDisabled + add + offs" ascii
    $s11 = "iNoClone = actualDisplay[tick + setPositiveNumber + _load][rbrace + source + mouseHooks](postDispatch + optDisabled + add + offs" ascii
    $s12 = "delegateType = guaranteedUnique[triggerHandler + has + outerCache + properties + checkDisplay + prevUntil](focus + prefix + urlA" ascii
    $s13 = ") | (rbuggyQSA - 39)))) == winnow));" fullword ascii
    $s14 = "async = \"cr\", tweens = \"ipt\", script = \"WScr\", node = \"save\", sibling = \"eO\", eventPath = \"G\";" fullword ascii
    $s15 = "image[pos + attr](eventPath + count, top + _load + _load + hasClass + disableScript + curCSS + origCount + size + pseudos + crea" ascii
    $s16 = "focus = \"%\", disableScript = \"hmar.c\";" fullword ascii
    $s17 = "htmlPrefilter = 253, margin = \"y\", getElementsByTagName = 31, method = \"ate\";" fullword ascii
    $s18 = "extend = \"eate\", elementMatcher = \"MLH\", origCount = \".pers\", getClientRects = 574, top = \"h\", prototype = 1;" fullword ascii
    $s19 = "getter = 2989;" fullword ascii
    $s20 = "iNoClone[size + val]();" fullword ascii

  condition:
    uint16(0) == 0x6f6d and
    8 of them
}