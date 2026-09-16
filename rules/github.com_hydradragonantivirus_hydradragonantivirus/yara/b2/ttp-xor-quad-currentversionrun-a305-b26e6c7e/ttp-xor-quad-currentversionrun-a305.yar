rule TTP_XOR_QUAD_CurrentVersionRun_a305 {
  strings:
    $key_a305 = { f0 6a [2] d4 64 [2] ff 48 [2] d1 6a [2] c5 71 [2] ca 6b [2] d4 76 [2] d6 77 [2] cd 71 [2] d1 76 [2] cd 59 }

  condition:
    any of them
}