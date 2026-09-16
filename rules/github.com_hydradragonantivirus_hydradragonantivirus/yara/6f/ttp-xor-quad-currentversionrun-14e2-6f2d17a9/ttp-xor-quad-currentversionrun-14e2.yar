rule TTP_XOR_QUAD_CurrentVersionRun_14e2 {
  strings:
    $key_14e2 = { 47 8d [2] 63 83 [2] 48 af [2] 66 8d [2] 72 96 [2] 7d 8c [2] 63 91 [2] 61 90 [2] 7a 96 [2] 66 91 [2] 7a be }

  condition:
    any of them
}