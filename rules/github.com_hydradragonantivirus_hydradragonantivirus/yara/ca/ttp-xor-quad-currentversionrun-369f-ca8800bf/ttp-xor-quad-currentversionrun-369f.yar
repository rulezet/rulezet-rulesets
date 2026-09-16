rule TTP_XOR_QUAD_CurrentVersionRun_369f {
  strings:
    $key_369f = { 65 f0 [2] 41 fe [2] 6a d2 [2] 44 f0 [2] 50 eb [2] 5f f1 [2] 41 ec [2] 43 ed [2] 58 eb [2] 44 ec [2] 58 c3 }

  condition:
    any of them
}