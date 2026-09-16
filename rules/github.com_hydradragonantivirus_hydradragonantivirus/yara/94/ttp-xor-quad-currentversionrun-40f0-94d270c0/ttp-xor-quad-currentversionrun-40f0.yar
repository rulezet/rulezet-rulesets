rule TTP_XOR_QUAD_CurrentVersionRun_40f0 {
  strings:
    $key_40f0 = { 13 9f [2] 37 91 [2] 1c bd [2] 32 9f [2] 26 84 [2] 29 9e [2] 37 83 [2] 35 82 [2] 2e 84 [2] 32 83 [2] 2e ac }

  condition:
    any of them
}