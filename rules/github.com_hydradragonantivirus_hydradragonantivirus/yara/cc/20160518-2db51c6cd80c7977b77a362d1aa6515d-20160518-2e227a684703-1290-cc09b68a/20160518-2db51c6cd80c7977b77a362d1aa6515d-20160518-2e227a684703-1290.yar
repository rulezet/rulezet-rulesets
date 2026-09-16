rule _20160518_2db51c6cd80c7977b77a362d1aa6515d_20160518_2e227a684703_1290 {
  meta:
    description = "datamaliciousorder - from files 20160518_2db51c6cd80c7977b77a362d1aa6515d.js, 20160518_2e227a684703aea1e5506ffd2ca826ef.js, 20160518_7e117e0744b3a01acaf7af0ffe8520a9.js, 20160519_d8d00c9317abe52d3781e345189c97b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e04e56729ff9d5a08b4e9b3ebbe5ff2bba0bfb31320a1fdae96c5073242c751"
    hash2       = "387f7c7c1e4671de7cd233101eef090a777e6655df8d0ad6afa9ca1858b4696b"
    hash3       = "91166b16ce7b2246bd6fd84c96534eadefc5a870205d236d615c858915e44bb6"
    hash4       = "ba8b9a28a0543e8472ff7a71e39774c04888f227bb61efa71f2d2166f4ba7616"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* c  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* c  */, A8name /* c  *" ascii
    $s3 = "dot1 /* c  */= true;/* c  */" fullword ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* c  */;};" fullword ascii
    $s5 = "newtonsCradle1 /* c  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}