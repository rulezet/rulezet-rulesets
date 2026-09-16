rule TTP_XOR_WriteProcessMemory_7f93 {
  strings:
    $key_7f93 = { 28 e1 [2] 1a c3 [2] 1c f6 [2] 32 f6 [2] 0d ea }

  condition:
    any of them
}