rule TTP_XOR_QUAD_CurrentVersionRun_fade {
  strings:
    $key_fade = { a9 b1 [2] 8d bf [2] a6 93 [2] 88 b1 [2] 9c aa [2] 93 b0 [2] 8d ad [2] 8f ac [2] 94 aa [2] 88 ad [2] 94 82 }

  condition:
    any of them
}