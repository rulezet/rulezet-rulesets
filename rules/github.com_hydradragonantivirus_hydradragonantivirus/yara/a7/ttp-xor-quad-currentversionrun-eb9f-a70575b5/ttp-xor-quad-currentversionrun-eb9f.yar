rule TTP_XOR_QUAD_CurrentVersionRun_eb9f {
  strings:
    $key_eb9f = { b8 f0 [2] 9c fe [2] b7 d2 [2] 99 f0 [2] 8d eb [2] 82 f1 [2] 9c ec [2] 9e ed [2] 85 eb [2] 99 ec [2] 85 c3 }

  condition:
    any of them
}