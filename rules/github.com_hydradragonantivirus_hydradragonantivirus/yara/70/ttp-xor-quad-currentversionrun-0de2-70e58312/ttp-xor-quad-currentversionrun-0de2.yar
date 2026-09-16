rule TTP_XOR_QUAD_CurrentVersionRun_0de2 {
  strings:
    $key_0de2 = { 5e 8d [2] 7a 83 [2] 51 af [2] 7f 8d [2] 6b 96 [2] 64 8c [2] 7a 91 [2] 78 90 [2] 63 96 [2] 7f 91 [2] 63 be }

  condition:
    any of them
}