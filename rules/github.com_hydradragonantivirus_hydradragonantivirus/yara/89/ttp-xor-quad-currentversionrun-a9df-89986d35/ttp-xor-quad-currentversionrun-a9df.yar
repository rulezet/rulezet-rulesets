rule TTP_XOR_QUAD_CurrentVersionRun_a9df {
  strings:
    $key_a9df = { fa b0 [2] de be [2] f5 92 [2] db b0 [2] cf ab [2] c0 b1 [2] de ac [2] dc ad [2] c7 ab [2] db ac [2] c7 83 }

  condition:
    any of them
}