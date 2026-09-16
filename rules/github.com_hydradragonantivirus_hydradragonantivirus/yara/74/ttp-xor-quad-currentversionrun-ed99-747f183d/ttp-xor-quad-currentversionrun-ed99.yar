rule TTP_XOR_QUAD_CurrentVersionRun_ed99 {
  strings:
    $key_ed99 = { be f6 [2] 9a f8 [2] b1 d4 [2] 9f f6 [2] 8b ed [2] 84 f7 [2] 9a ea [2] 98 eb [2] 83 ed [2] 9f ea [2] 83 c5 }

  condition:
    any of them
}