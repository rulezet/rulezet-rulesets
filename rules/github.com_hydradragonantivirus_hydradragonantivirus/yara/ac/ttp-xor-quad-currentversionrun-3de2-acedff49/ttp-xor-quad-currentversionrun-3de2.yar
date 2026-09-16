rule TTP_XOR_QUAD_CurrentVersionRun_3de2 {
  strings:
    $key_3de2 = { 6e 8d [2] 4a 83 [2] 61 af [2] 4f 8d [2] 5b 96 [2] 54 8c [2] 4a 91 [2] 48 90 [2] 53 96 [2] 4f 91 [2] 53 be }

  condition:
    any of them
}