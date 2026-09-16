rule TTP_XOR_QUAD_CurrentVersionRun_f6a2 {
  strings:
    $key_f6a2 = { a5 cd [2] 81 c3 [2] aa ef [2] 84 cd [2] 90 d6 [2] 9f cc [2] 81 d1 [2] 83 d0 [2] 98 d6 [2] 84 d1 [2] 98 fe }

  condition:
    any of them
}