rule TTP_XOR_QUAD_CurrentVersionRun_f7a2 {
  strings:
    $key_f7a2 = { a4 cd [2] 80 c3 [2] ab ef [2] 85 cd [2] 91 d6 [2] 9e cc [2] 80 d1 [2] 82 d0 [2] 99 d6 [2] 85 d1 [2] 99 fe }

  condition:
    any of them
}