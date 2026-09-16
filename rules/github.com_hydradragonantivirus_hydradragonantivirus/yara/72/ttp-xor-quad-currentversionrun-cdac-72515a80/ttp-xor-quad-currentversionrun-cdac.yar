rule TTP_XOR_QUAD_CurrentVersionRun_cdac {
  strings:
    $key_cdac = { 9e c3 [2] ba cd [2] 91 e1 [2] bf c3 [2] ab d8 [2] a4 c2 [2] ba df [2] b8 de [2] a3 d8 [2] bf df [2] a3 f0 }

  condition:
    any of them
}