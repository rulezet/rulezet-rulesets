rule sig_20160308_a21e4c77420ad289fc7af4da1384aefb {
  meta:
    description = "datamaliciousorder - file 20160308_a21e4c77420ad289fc7af4da1384aefb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da12a9d140237e265aa1c07329dc9e1efc8d892cf0e9d1fb09670625a2f5de85"

  strings:
    $s1  = "udataCur = ownerDocument[camelCase + postDispatch + propFilter + bp + interval + srcElements + active](responseType + sortDetach" ascii
    $s2  = "special[cleanData](exports + submit, stateString + rnamespace + cssNormalTransform + eq + prefilterOrFactory + unqueued + maxIte" ascii
    $s3  = "ed + script) + ridentifier + cssNormalTransform + result + noCloneChecked + xhr;" fullword ascii
    $s4  = " 184), (siblingCheck ^ 0)))) ^ (((maxWidth + 257) ^ (Math.pow(JSON, 2) - triggered)) / (173, strAbort, 51, filters) * (2 + sibli" ascii
    $s5  = "  funescape[count + access][remove + buildFragment](((Math.pow(matchIndexes, 2) - iframe) - (26 * filters + 14)));" fullword ascii
    $s6  = "second[getAttribute + find]();" fullword ascii
    $s7  = "rations + num + defaultPrevented + invert, !((((pageX - 37) ^ (((nativeStatusText / 30) - (id / 1)) | ((oldfire | 16), (prefix +" ascii
    $s8  = "second[radioValue + cssNormalTransform + implementation](udataCur, (5 - dataAttr));" fullword ascii
    $s9  = "special[cleanData](exports + submit, stateString + rnamespace + cssNormalTransform + eq + prefilterOrFactory + unqueued + maxIte" ascii
    $s10 = "lock = \"ition\", script = \"MP%/\", triggerHandler = \"onse\";" fullword ascii
    $s11 = "head = \"Cr\";" fullword ascii
    $s12 = "udataCur = ownerDocument[camelCase + postDispatch + propFilter + bp + interval + srcElements + active](responseType + sortDetach" ascii
    $s13 = "special = funescape[count + access][head + fxNow + cssNumber](cacheLength + booleans + teardown + ret);" fullword ascii
    $s14 = "ownerDocument = unwrap[addHandle + matchers + cssShow](obj + onload + position + rtagName);" fullword ascii
    $s15 = "PI[boxSizingReliableVal + lock] = ((0 | siblingCheck) ^ (0 ^ siblingCheck));" fullword ascii
    $s16 = "second[fadeTo + orig](special[to + resolveValues + triggerHandler + diff]);" fullword ascii
    $s17 = "interval = (function Object.prototype.inspectPrefiltersOrTransports() {" fullword ascii
    $s18 = "while(special[rescape + left + cssNormalTransform] < ((documentIsHTML & 3) * (siblingCheck | 2))) {" fullword ascii
    $s19 = "invert = \"g\";" fullword ascii
    $s20 = "access = \"pt\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}