rule TTP_XOR_QUAD_CurrentVersionRun_379f {
  strings:
    $key_379f = { 64 f0 [2] 40 fe [2] 6b d2 [2] 45 f0 [2] 51 eb [2] 5e f1 [2] 40 ec [2] 42 ed [2] 59 eb [2] 45 ec [2] 59 c3 }

  condition:
    any of them
}