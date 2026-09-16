rule sig_20160308_edb7fdf4cc138cda82f54deee37dfb9f {
  meta:
    description = "datamaliciousorder - file 20160308_edb7fdf4cc138cda82f54deee37dfb9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5aee8e34f3f8d89f0ddd745623359bc0471c2eb5714e10522f54bec0db8f5c8"

  strings:
    $x1  = "clearInterval[Expr](target, fns + webkitMatchesSelector + cos + start + div + rfocusable + createTextNode + isPropagationStopped" ascii
    $s2  = "progressContexts = pop[strAbort + unqueued + responseHeadersString + context + allTypes + p + holdReady + temp](onreadystatechan" ascii
    $s3  = "progressContexts = pop[strAbort + unqueued + responseHeadersString + context + allTypes + p + holdReady + temp](onreadystatechan" ascii
    $s4  = "tmp[rsubmittable + content][keepScripts](((6693 - classes) + (4333 * rbuggyMatches + 1394)));" fullword ascii
    $s5  = " + offset, !(pipe < (((Math.pow(((Math.pow(417, rbuggyMatches) - 173349) / (Math.pow(anim, 2) - qsa)), ((1 * rbuggyMatches) + (3" ascii
    $s6  = "^ 355) / (Math.pow(pipe, 2) - amd)))) & (Math.pow(((14 - curCSSLeft) * 2) * ((indirect & 1) | (clazz / 8)) * ((disable & 211), (" ascii
    $s7  = "tmp = (5 * rbuggyMatches * (38 / amd) * (20 / pixelPosition) * (2 & cssText), (((946 - postFinder) / 7 * rbuggyMatches * 3), thi" ascii
    $s8  = "clearInterval[Expr](target, fns + webkitMatchesSelector + cos + start + div + rfocusable + createTextNode + isPropagationStopped" ascii
    $s9  = "clearInterval = tmp[rsubmittable + content][msMatchesSelector + nodeIndex + rprotocol](accepts + file + nodeName + maxIterations" ascii
    $s10 = "clearInterval = tmp[rsubmittable + content][msMatchesSelector + nodeIndex + rprotocol](accepts + file + nodeName + maxIterations" ascii
    $s11 = "target = \"GET\";" fullword ascii
    $s12 = "temp = \"gs\", cloneCopyEvent = \"rip\", p = \"t\", pipe = 5;" fullword ascii
    $s13 = "tmp[Symbol + augmentWidthOrHeight][keepScripts](((amd + 40) ^ (scale * 3 + bySet)));" fullword ascii
    $s14 = "nodes = tmp[complete + simple + guaranteedUnique + p][subordinate + selector + groups + rprotocol](unbind + tuples + prefix);" fullword ascii
    $s15 = "nodes[access + compare]();" fullword ascii
    $s16 = "opt = tmp[complete + cloneCopyEvent + p];" fullword ascii
    $s17 = "ge + nativeStatusText) + sort + fail + proxy + parentOffset + writable;" fullword ascii
    $s18 = "content = \"pt\";" fullword ascii
    $s19 = " + random);" fullword ascii
    $s20 = "while (clearInterval[optionSet + triggered] < ((fixHook / 47) & (rbuggyMatches * 2))) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}