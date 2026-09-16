rule TTP_XOR_WriteProcessMemory_881a {
  strings:
    $key_881a = { df 68 [2] ed 4a [2] eb 7f [2] c5 7f [2] fa 63 }

  condition:
    any of them
}