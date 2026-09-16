rule TTP_XOR_QUAD_CurrentVersionRun_e5a2 {
  strings:
    $key_e5a2 = { b6 cd [2] 92 c3 [2] b9 ef [2] 97 cd [2] 83 d6 [2] 8c cc [2] 92 d1 [2] 90 d0 [2] 8b d6 [2] 97 d1 [2] 8b fe }

  condition:
    any of them
}