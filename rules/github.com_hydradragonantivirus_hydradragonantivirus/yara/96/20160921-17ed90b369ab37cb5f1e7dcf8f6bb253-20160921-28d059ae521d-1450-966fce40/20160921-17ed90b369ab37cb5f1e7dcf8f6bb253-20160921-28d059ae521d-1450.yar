rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_28d059ae521d_1450 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_28d059ae521dbabe2afdc3bfd464938c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"

  strings:
    $s1  = "{return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s2  = "eturn \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})()," ascii
    $s3  = "eturn \"DYs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4  = "return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MDb\";})(" ascii
    $s5  = "){return \"Tb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MMz\";}" ascii
    $s6  = "turn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MBb\";})()" ascii
    $s7  = "KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"SEo\";})(),(funct" ascii
    $s8  = "ion f000(){return \"KDh\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s9  = ";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f0" ascii
    $s10 = "w\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Um\";})(),(function" ascii
    $s11 = "tion f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RLk\";})(),(function f000(){retur" ascii
    $s12 = "on f000(){return \"Yz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return " ascii
    $s13 = "00(){return \"EZu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}