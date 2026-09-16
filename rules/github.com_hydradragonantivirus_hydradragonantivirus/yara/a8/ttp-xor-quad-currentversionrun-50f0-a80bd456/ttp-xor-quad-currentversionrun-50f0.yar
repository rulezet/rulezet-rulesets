rule TTP_XOR_QUAD_CurrentVersionRun_50f0 {
  strings:
    $key_50f0 = { 03 9f [2] 27 91 [2] 0c bd [2] 22 9f [2] 36 84 [2] 39 9e [2] 27 83 [2] 25 82 [2] 3e 84 [2] 22 83 [2] 3e ac }

  condition:
    any of them
}