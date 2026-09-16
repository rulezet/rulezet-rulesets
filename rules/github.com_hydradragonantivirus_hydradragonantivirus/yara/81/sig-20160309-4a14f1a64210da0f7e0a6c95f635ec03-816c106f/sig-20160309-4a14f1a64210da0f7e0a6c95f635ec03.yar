rule sig_20160309_4a14f1a64210da0f7e0a6c95f635ec03 {
  meta:
    description = "datamaliciousorder - file 20160309_4a14f1a64210da0f7e0a6c95f635ec03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6c869f9a398774cf08d0535cce26b0c9690854eb4b3560a1f5b6614225a7f4"

  strings:
    $s1  = "e = speeds[animated + nodeName + condense + bp + postFilter + pageY + childNodes + disableScript](defaultPrevented + bind) + att" ascii
    $s2  = "m[getAttributeNode](propFix, activeElement + classNames + rnoContent + matched + iterator + clearQueue + replaceChild + curTop, " ascii
    $s3  = "e = speeds[animated + nodeName + condense + bp + postFilter + pageY + childNodes + disableScript](defaultPrevented + bind) + att" ascii
    $s4  = "m = detach[arr + root + clearInterval][markFunction + compare + isPropagationStopped + removeData + prevAll](clientX + iNoClone " ascii
    $s5  = "m = detach[arr + root + clearInterval][markFunction + compare + isPropagationStopped + removeData + prevAll](clientX + iNoClone " ascii
    $s6  = "detach[sortStable + getWidthOrHeight + clearInterval][contains](((200037 ^ conv2) / (1 | to)));" fullword ascii
    $s7  = "oldCallbacks = detach[class2type + propHooks][stateVal + setter + bp + compareDocumentPosition](rsingleTag + getAttribute + trig" ascii
    $s8  = "oldCallbacks = detach[class2type + propHooks][stateVal + setter + bp + compareDocumentPosition](rsingleTag + getAttribute + trig" ascii
    $s9  = "ridentifier[status] = ((defaultDisplay, 1) & (map + 0));" fullword ascii
    $s10 = "aches + qsa + dataUser + hidden;" fullword ascii
    $s11 = "+ slow + username);" fullword ascii
    $s12 = " apply)), ((12 & transports) | (36 ^ html)), ((1 + -map) | 0)) ^ (((map * 0) ^ (parentNode, 37, cached)) ^ ((1 & cached) & (1 * " ascii
    $s13 = "fire[jqXHR + doScroll + unwrap + postFilter] = ((cached) | (1 & cached));" fullword ascii
    $s14 = "gerHandler + file);" fullword ascii
    $s15 = "ntexts) + (1 * map)), this));" fullword ascii
    $s16 = "size[abort + newSelector]();" fullword ascii
    $s17 = "which = m[rcheckableType + n];" fullword ascii
    $s18 = "detach = ((3 & detectDuplicates) * (1 | complete) * (1 ^ resolveContexts) * (0 ^ detectDuplicates) * (2 ^ map), (((2 & resolveCo" ascii
    $s19 = "fadeIn = \"wri\", clearQueue = \"n.s\", setter = \"teObj\", root = \"rip\", arr = \"WSc\";" fullword ascii
    $s20 = "detach = ((3 & detectDuplicates) * (1 | complete) * (1 ^ resolveContexts) * (0 ^ detectDuplicates) * (2 ^ map), (((2 & resolveCo" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}