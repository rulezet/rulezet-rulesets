rule sig_20160309_38264f381b2600149021e56f299de9f4 {
  meta:
    description = "datamaliciousorder - file 20160309_38264f381b2600149021e56f299de9f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a51e0c3b988f885970c7fd9d82245d56e7039fb2e2f759a932dade977fd7a9ad"

  strings:
    $x1  = "returned[rmouseEvent](valueParts, divStyle + temp + rrun + Expr + pseudo + optDisabled + callback + getPropertyValue + setter + " ascii
    $s2  = "sel = factory[all + always + linear](isXML + file + contents + target + write);" fullword ascii
    $s3  = "t) - ((1728 / htmlPrefilter))), (((0 | propFilter) / (420 / name)) ^ ((31 + scripts) / (Math.pow(26, rbracket) - 636)))) - ((Mat" ascii
    $s4  = "completed[initial](lastModified.postDispatch(), ((parsed + -1) | (parsed & 0)), (propFilter & 0));" fullword ascii
    $s5  = "h.pow((rsubmittable, 158, off, 3), (parsed + 1)) - (rbracket * 2 + parsed)) * (22 / defaultDisplay) + ((195 / name) / (155, getE" ascii
    $s6  = "originalEvent[ridentifier + display + contents][hooks + rcombinators](((787 ^ notify) & (1293 * defaultDisplay + 1136)));" fullword ascii
    $s7  = "returned[rmouseEvent](valueParts, divStyle + temp + rrun + Expr + pseudo + optDisabled + callback + getPropertyValue + setter + " ascii
    $s8  = "removeEvent = \"Env\", marginDiv = \"ream\", dataAndEvents = 218, isArray = \"ADO\", target = \".She\";" fullword ascii
    $s9  = "serializeArray = \"%TEMP%\";" fullword ascii
    $s10 = "originalEvent = (((287 - slow) - (Math.pow(43, rbracket) - 1800)), ((parsed ^ (2 * rparentsprev)), this));" fullword ascii
    $s11 = "safeActiveElement + tabIndex + maxWidth + simulate + defaultExtra + responseType, !(7 == (Math.pow(((rbracket) * (16 ^ hasConten" ascii
    $s12 = "write = \"ll\", outermostContext = \"i\", hasContent = 13, valueParts = \"GET\";" fullword ascii
    $s13 = "owner = originalEvent[selection + inspectPrefiltersOrTransports][winnow + qsaError + linear](isArray + tweens + detach + selecte" ascii
    $s14 = "owner = originalEvent[selection + inspectPrefiltersOrTransports][winnow + qsaError + linear](isArray + tweens + detach + selecte" ascii
    $s15 = "returned = originalEvent[namespaces + finalValue][rfocusMorph + top + rscriptType](wrapAll + copyIsArray + unit + opener);" fullword ascii
    $s16 = "scripts = 49, selectedIndex = \"t\", name = 15, rbracket = 2, all = \"Create\", inspectPrefiltersOrTransports = \"pt\";" fullword ascii
    $s17 = "owner[msMatchesSelector + overrideMimeType + outermostContext + disabled + stopOnFalse](lastModified, (2 + propFilter));" fullword ascii
    $s18 = "rcombinators = \"p\", string = \"/\", namespaces = \"WScr\", getPropertyValue = \"te\", propFilter = 0;" fullword ascii
    $s19 = "owner[bup + dirruns]();" fullword ascii
    $s20 = "rsubmittable = 148, temp = \"/d\";" fullword ascii

  condition:
    uint16(0) == 0x6372 and
    1 of ($x*) and 4 of them
}