rule TTP_XOR_QUAD_CurrentVersionRun_3098 {
  strings:
    $key_3098 = { 63 f7 [2] 47 f9 [2] 6c d5 [2] 42 f7 [2] 56 ec [2] 59 f6 [2] 47 eb [2] 45 ea [2] 5e ec [2] 42 eb [2] 5e c4 }

  condition:
    any of them
}