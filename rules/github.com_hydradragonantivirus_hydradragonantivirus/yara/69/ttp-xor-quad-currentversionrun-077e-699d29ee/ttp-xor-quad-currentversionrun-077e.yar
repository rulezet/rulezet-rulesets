rule TTP_XOR_QUAD_CurrentVersionRun_077e {
  strings:
    $key_077e = { 54 11 [2] 70 1f [2] 5b 33 [2] 75 11 [2] 61 0a [2] 6e 10 [2] 70 0d [2] 72 0c [2] 69 0a [2] 75 0d [2] 69 22 }

  condition:
    any of them
}