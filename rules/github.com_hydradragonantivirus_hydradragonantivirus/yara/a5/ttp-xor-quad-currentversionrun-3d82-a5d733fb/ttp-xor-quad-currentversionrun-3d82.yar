rule TTP_XOR_QUAD_CurrentVersionRun_3d82 {
  strings:
    $key_3d82 = { 6e ed [2] 4a e3 [2] 61 cf [2] 4f ed [2] 5b f6 [2] 54 ec [2] 4a f1 [2] 48 f0 [2] 53 f6 [2] 4f f1 [2] 53 de }

  condition:
    any of them
}