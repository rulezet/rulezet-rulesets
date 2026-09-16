rule TTP_XOR_QUAD_CurrentVersionRun_20f0 {
  strings:
    $key_20f0 = { 73 9f [2] 57 91 [2] 7c bd [2] 52 9f [2] 46 84 [2] 49 9e [2] 57 83 [2] 55 82 [2] 4e 84 [2] 52 83 [2] 4e ac }

  condition:
    any of them
}