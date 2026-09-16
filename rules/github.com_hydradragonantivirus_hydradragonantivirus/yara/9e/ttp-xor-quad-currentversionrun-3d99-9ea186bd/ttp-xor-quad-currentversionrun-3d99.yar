rule TTP_XOR_QUAD_CurrentVersionRun_3d99 {
  strings:
    $key_3d99 = { 6e f6 [2] 4a f8 [2] 61 d4 [2] 4f f6 [2] 5b ed [2] 54 f7 [2] 4a ea [2] 48 eb [2] 53 ed [2] 4f ea [2] 53 c5 }

  condition:
    any of them
}