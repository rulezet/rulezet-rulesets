rule _20160921_98f234a378a6dd4e51c1730a4a700647_20160921_9aa040f4b657_5577 {
  meta:
    description = "datamaliciousorder - from files 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash2       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"
    hash3       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s2 = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000" ascii
    $s3 = " f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s4 = "),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii
    $s5 = "turn \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}