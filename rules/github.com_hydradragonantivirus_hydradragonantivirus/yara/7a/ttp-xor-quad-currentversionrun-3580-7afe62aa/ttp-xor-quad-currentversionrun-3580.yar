rule TTP_XOR_QUAD_CurrentVersionRun_3580 {
  strings:
    $key_3580 = { 66 ef [2] 42 e1 [2] 69 cd [2] 47 ef [2] 53 f4 [2] 5c ee [2] 42 f3 [2] 40 f2 [2] 5b f4 [2] 47 f3 [2] 5b dc }

  condition:
    any of them
}