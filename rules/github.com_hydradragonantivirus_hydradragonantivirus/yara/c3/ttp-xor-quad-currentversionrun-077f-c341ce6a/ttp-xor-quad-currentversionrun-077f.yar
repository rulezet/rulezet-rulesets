rule TTP_XOR_QUAD_CurrentVersionRun_077f {
  strings:
    $key_077f = { 54 10 [2] 70 1e [2] 5b 32 [2] 75 10 [2] 61 0b [2] 6e 11 [2] 70 0c [2] 72 0d [2] 69 0b [2] 75 0c [2] 69 23 }

  condition:
    any of them
}