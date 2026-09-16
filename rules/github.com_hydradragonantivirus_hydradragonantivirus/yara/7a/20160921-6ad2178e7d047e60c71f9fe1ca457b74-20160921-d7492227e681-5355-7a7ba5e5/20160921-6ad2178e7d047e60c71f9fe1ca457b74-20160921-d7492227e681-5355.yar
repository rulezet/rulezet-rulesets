rule _20160921_6ad2178e7d047e60c71f9fe1ca457b74_20160921_d7492227e681_5355 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_d7492227e681b1689bfc5442a91a169e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash2       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"

  strings:
    $s1 = "(),(function f000(){return \"Oh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"EZu\";})(),(function f000(" ascii
    $s2 = "eturn \"Vj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SEo\";})()," ascii
    $s3 = "n f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"" ascii
    $s4 = "(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"MBb\";})(),(function f000(){" ascii
    $s5 = "rn \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}