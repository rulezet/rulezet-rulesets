rule TTP_XOR_QUAD_CurrentVersionRun_077c {
  strings:
    $key_077c = { 54 13 [2] 70 1d [2] 5b 31 [2] 75 13 [2] 61 08 [2] 6e 12 [2] 70 0f [2] 72 0e [2] 69 08 [2] 75 0f [2] 69 20 }

  condition:
    any of them
}