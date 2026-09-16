rule PEiD_02314_Unknown_encryptor__1__ {
  meta:
    description = "[Unknown encryptor (1)]"
    ep_only     = "true"

  strings:
    $a = { EB ?? 2E 90 ?? ?? 8C DB 8C CA 8E DA FA 8B EC BE ?? ?? BC ?? ?? BF }

  condition:
    $a
}