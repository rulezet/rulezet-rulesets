rule sig_20160308_318cd5b8a852eabd144bb4b7c8645e15 {
  meta:
    description = "datamaliciousorder - file 20160308_318cd5b8a852eabd144bb4b7c8645e15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7155411c382ba291b86833ceff649b1fa48bb5950ee411c4406d7de7d3c151d7"

  strings:
    $s1  = "selectors[iterator + msFullscreenElement](detach, nid + pixelPosition + contexts + next + finalText + triggered + stateString + " ascii
    $s2  = "get + 3) | ((charCode | 3) + (text ^ 0))), ((root, 2) + (whitespace - 4))) - (((text | 19) * evt * 2 + (emptyStyle - 6)) ^ ((las" ascii
    $s3  = "nodeName[excess + gotoEnd + rmouseEvent][forward + bulk](((7578 ^ currentTime) - (2170 + list)));" fullword ascii
    $s4  = "attrHandle = collection[finish + marginLeft + merge + run + msFullscreenElement + getAll + divStyle + owner + contexts](styles +" ascii
    $s5  = "checkDisplay, !((((((evt | 66) ^ (transports, 62, parseHTML, 21)), ((duration / 13) ^ (Expr * 2 + contains)), (29 * isXMLDoc - (" ascii
    $s6  = "scrollLeft[preMap + noConflict] = ((0 ^ text) / (Math.pow(39, evt) - 1479));" fullword ascii
    $s7  = "allTypes = nodeName[setup + b + disableScript];" fullword ascii
    $s8  = "parse = \"rip\", detach = \"GET\", stateString = \"m/89o\", nid = \"http\", teardown = 20;" fullword ascii
    $s9  = "attrHandle = collection[finish + marginLeft + merge + run + msFullscreenElement + getAll + divStyle + owner + contexts](styles +" ascii
    $s10 = "52 + teardown)), ((0 ^ charCode) ^ (0 / clientTop))) * (Math.pow((62 / amd) * (0 | rfocusMorph), ((1 + charCode) | (0 ^ text))) " ascii
    $s11 = "ttrs / 37) + evt)) * (1 * evt) * ((61 & transports), 2 * contains * 7, (text | 2)) * ((charCode | 2) + (text ^ 0)))) == ((((preD" ascii
    $s12 = "var forward = \"Sle\"," fullword ascii
    $s13 = "nodeName[setup + remove + rmouseEvent][parts](((58 ^ firstElementChild) ^ (51 & cloneCopyEvent)));" fullword ascii
    $s14 = "diff[rmouseEvent + slideUp] = (1 + text);" fullword ascii
    $s15 = "selectors = nodeName[rfxtypes + checkbox + rmouseEvent][ontype + beforeunload + replaceWith + selector](closest + scrollTop + co" ascii
    $s16 = "nodeName = (((13 & stored) * 2 + (reject / 14)), (((fixInput & 31) | (destElements / 14)), this));" fullword ascii
    $s17 = "wait = andSelf + guaranteedUnique + msFullscreenElement;" fullword ascii
    $s18 = "selectors[iterator + msFullscreenElement](detach, nid + pixelPosition + contexts + next + finalText + triggered + stateString + " ascii
    $s19 = "collection = allTypes[when + always + unshift + replaceWith + selector](rfxtypes + view + createPositionalPseudo);" fullword ascii
    $s20 = "while(selectors[firstChild + contexts + matcherIn] < (6 & nextSibling)) {" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}