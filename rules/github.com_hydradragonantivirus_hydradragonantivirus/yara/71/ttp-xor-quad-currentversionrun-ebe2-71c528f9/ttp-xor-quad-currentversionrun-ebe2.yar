rule TTP_XOR_QUAD_CurrentVersionRun_ebe2 {
  strings:
    $key_ebe2 = { b8 8d [2] 9c 83 [2] b7 af [2] 99 8d [2] 8d 96 [2] 82 8c [2] 9c 91 [2] 9e 90 [2] 85 96 [2] 99 91 [2] 85 be }

  condition:
    any of them
}