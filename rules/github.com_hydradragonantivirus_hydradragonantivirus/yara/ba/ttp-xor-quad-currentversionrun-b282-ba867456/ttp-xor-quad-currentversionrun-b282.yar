rule TTP_XOR_QUAD_CurrentVersionRun_b282 {
  strings:
    $key_b282 = { e1 ed [2] c5 e3 [2] ee cf [2] c0 ed [2] d4 f6 [2] db ec [2] c5 f1 [2] c7 f0 [2] dc f6 [2] c0 f1 [2] dc de }

  condition:
    any of them
}