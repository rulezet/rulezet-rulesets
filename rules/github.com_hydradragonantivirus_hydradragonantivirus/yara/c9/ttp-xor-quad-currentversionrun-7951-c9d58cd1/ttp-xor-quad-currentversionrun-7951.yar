rule TTP_XOR_QUAD_CurrentVersionRun_7951 {
  strings:
    $key_7951 = { 2a 3e [2] 0e 30 [2] 25 1c [2] 0b 3e [2] 1f 25 [2] 10 3f [2] 0e 22 [2] 0c 23 [2] 17 25 [2] 0b 22 [2] 17 0d }

  condition:
    any of them
}