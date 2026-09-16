rule sig_20160308_7e4045c4ff991616440a8c143cf2419d {
  meta:
    description = "datamaliciousorder - file 20160308_7e4045c4ff991616440a8c143cf2419d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdd1c1dbc9e44eb57faf7dff3d3fc2ae7eb927950ef5fae064a05ba1cbc0e44f"

  strings:
    $s1  = "tokenCache[dataShow](ajaxSettings, delay + seed + xhrFields + ct + getElementsByName + aup + rheaders + rbracket + deepDataAndEv" ascii
    $s2  = "slideDown[currentTarget + round][allTypes + tuple](((rfocusable / 42) | (attachEvent / 22)));" fullword ascii
    $s3  = "var rcheckableType = \"%TEMP%\"," fullword ascii
    $s4  = "completed[setTimeout + mouseenter + what + charset](len, (139, version, 232, minWidth));" fullword ascii
    $s5  = "while(tokenCache[clearTimeout + msFullscreenElement + on] < (2 * (getAttributeNode / 41))) {" fullword ascii
    $s6  = "completed = slideDown[event + invert + round][id + charset + compilerCache + round](elementMatchers + nid + responseHeaders + tw" ascii
    $s7  = "th) & ((307 - pixelPosition), 97, (when & 98), (hover & 113))))) > speeds));" fullword ascii
    $s8  = "completed = slideDown[event + invert + round][id + charset + compilerCache + round](elementMatchers + nid + responseHeaders + tw" ascii
    $s9  = "tokenCache[dataShow](ajaxSettings, delay + seed + xhrFields + ct + getElementsByName + aup + rheaders + rbracket + deepDataAndEv" ascii
    $s10 = ".pow(((duplicates ^ 1) ^ (resolve / 35)), ((stopPropagation & 2) | (finalValue * 2))) - ((handleObjIn | 432) / (Math.pow(curCSS," ascii
    $s11 = "relative = \".scr\";" fullword ascii
    $s12 = "ents, !(((((stopPropagation & 3) * (parent, 61, stopPropagation) - (1 | (duplicates | 8))) ^ (duplicates & 1)) | (Math.pow((Math" ascii
    $s13 = "completed[iterator](tokenCache[timeoutTimer + teardown + charset + width + winnow]);" fullword ascii
    $s14 = "then = \"at\", ajaxSettings = \"GET\";" fullword ascii
    $s15 = "timeoutTimer = \"Re\", unqueued = \"WScri\", sort = \"Cre\", getElementsByName = \".free.\";" fullword ascii
    $s16 = "success = textContent;" fullword ascii
    $s17 = "margin = slideDown[rbuggyMatches + defaultExtra + w];" fullword ascii
    $s18 = "len = preDispatch[overflowX + handle + optionSet + timers + prevUntil + click + nType + cssNumber](rcheckableType + doScroll) + " ascii
    $s19 = "len = preDispatch[overflowX + handle + optionSet + timers + prevUntil + click + nType + cssNumber](rcheckableType + doScroll) + " ascii
    $s20 = "sortOrder + pageXOffset + relative;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}