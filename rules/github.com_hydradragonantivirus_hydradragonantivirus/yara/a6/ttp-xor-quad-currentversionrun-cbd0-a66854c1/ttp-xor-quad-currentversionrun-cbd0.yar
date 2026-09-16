rule TTP_XOR_QUAD_CurrentVersionRun_cbd0 {
  strings:
    $key_cbd0 = { 98 bf [2] bc b1 [2] 97 9d [2] b9 bf [2] ad a4 [2] a2 be [2] bc a3 [2] be a2 [2] a5 a4 [2] b9 a3 [2] a5 8c }

  condition:
    any of them
}