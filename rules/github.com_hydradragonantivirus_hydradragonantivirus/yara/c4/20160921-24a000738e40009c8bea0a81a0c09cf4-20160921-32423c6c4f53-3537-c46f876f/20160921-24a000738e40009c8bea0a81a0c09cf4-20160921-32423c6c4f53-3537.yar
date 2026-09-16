rule _20160921_24a000738e40009c8bea0a81a0c09cf4_20160921_32423c6c4f53_3537 {
  meta:
    description = "datamaliciousorder - from files 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash2       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash3       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"

  strings:
    $s1 = "nction f000(){return \"PTs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qj\";})(),(function f000(){retu" ascii
    $s2 = "Gn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BMj\";})(),(functio" ascii
    $s3 = " \"WIj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"BQb\";})(),(fun" ascii
    $s4 = "eturn \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(" ascii
    $s5 = "on f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s6 = "00(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MBb\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}