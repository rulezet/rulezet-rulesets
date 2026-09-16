rule TTP_XOR_QUAD_CurrentVersionRun_3d83 {
  strings:
    $key_3d83 = { 6e ec [2] 4a e2 [2] 61 ce [2] 4f ec [2] 5b f7 [2] 54 ed [2] 4a f0 [2] 48 f1 [2] 53 f7 [2] 4f f0 [2] 53 df }

  condition:
    any of them
}