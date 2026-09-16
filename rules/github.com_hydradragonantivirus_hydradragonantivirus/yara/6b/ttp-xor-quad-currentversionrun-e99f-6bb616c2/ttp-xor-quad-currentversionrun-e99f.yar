rule TTP_XOR_QUAD_CurrentVersionRun_e99f {
  strings:
    $key_e99f = { ba f0 [2] 9e fe [2] b5 d2 [2] 9b f0 [2] 8f eb [2] 80 f1 [2] 9e ec [2] 9c ed [2] 87 eb [2] 9b ec [2] 87 c3 }

  condition:
    any of them
}