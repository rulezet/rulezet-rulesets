rule TTP_XOR_QUAD_CurrentVersionRun_6580 {
  strings:
    $key_6580 = { 36 ef [2] 12 e1 [2] 39 cd [2] 17 ef [2] 03 f4 [2] 0c ee [2] 12 f3 [2] 10 f2 [2] 0b f4 [2] 17 f3 [2] 0b dc }

  condition:
    any of them
}