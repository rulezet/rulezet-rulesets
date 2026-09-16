rule TTP_XOR_QUAD_CurrentVersionRun_ede2 {
  strings:
    $key_ede2 = { be 8d [2] 9a 83 [2] b1 af [2] 9f 8d [2] 8b 96 [2] 84 8c [2] 9a 91 [2] 98 90 [2] 83 96 [2] 9f 91 [2] 83 be }

  condition:
    any of them
}