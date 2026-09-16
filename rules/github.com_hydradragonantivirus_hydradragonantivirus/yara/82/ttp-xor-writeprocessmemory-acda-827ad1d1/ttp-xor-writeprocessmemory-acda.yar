rule TTP_XOR_WriteProcessMemory_acda {
  strings:
    $key_acda = { fb a8 [2] c9 8a [2] cf bf [2] e1 bf [2] de a3 }

  condition:
    any of them
}