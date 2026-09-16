rule TTP_XOR_QUAD_CurrentVersionRun_cdaf {
  strings:
    $key_cdaf = { 9e c0 [2] ba ce [2] 91 e2 [2] bf c0 [2] ab db [2] a4 c1 [2] ba dc [2] b8 dd [2] a3 db [2] bf dc [2] a3 f3 }

  condition:
    any of them
}