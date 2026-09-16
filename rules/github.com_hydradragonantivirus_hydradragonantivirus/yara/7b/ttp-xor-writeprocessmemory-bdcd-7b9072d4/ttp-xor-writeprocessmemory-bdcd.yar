rule TTP_XOR_WriteProcessMemory_bdcd {
  strings:
    $key_bdcd = { ea bf [2] d8 9d [2] de a8 [2] f0 a8 [2] cf b4 }

  condition:
    any of them
}