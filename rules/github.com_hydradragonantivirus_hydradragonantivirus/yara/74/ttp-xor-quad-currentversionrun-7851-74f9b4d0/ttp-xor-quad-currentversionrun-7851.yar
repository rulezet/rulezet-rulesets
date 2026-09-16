rule TTP_XOR_QUAD_CurrentVersionRun_7851 {
  strings:
    $key_7851 = { 2b 3e [2] 0f 30 [2] 24 1c [2] 0a 3e [2] 1e 25 [2] 11 3f [2] 0f 22 [2] 0d 23 [2] 16 25 [2] 0a 22 [2] 16 0d }

  condition:
    any of them
}