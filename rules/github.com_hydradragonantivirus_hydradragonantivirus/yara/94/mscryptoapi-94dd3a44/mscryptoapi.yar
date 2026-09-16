rule MSCryptoApi
{
    meta:
        description = "Provider names often present when using the Microsoft Crypto API"
        author = "@larsborn"
        created_at = "2021-01-03"
        reference = "https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptographic-provider-names"
        example_hash_01 = "67ecc3b8c6057090c7982883e8d9d0389a8a8f6e8b00f9e9b73c45b008241322"
        DaysofYARA = "7/100"
    strings:
                $MS_DEF_DH_SCHANNEL_PROV = "Microsoft DH Schannel Cryptographic Provider"
                $MS_DEF_DSS_DH_PROV = "Microsoft Base DSS and Diffie-Hellman Cryptographic Provider"
                $MS_DEF_DSS_PROV = "Microsoft Base DSS Cryptographic Provider"
                $MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0"
                $MS_DEF_RSA_SCHANNEL_PROV = "Microsoft RSA Schannel Cryptographic Provider"
                $MS_DEF_RSA_SIG_PROV = "Microsoft RSA Signature Cryptographic Provider"
                $MS_ENH_DSS_DH_PROV = "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider"
                        $MS_ENH_RSA_AES_PROV = "Microsoft Enhanced RSA and AES Cryptographic Provider"
                $MS_ENHANCED_PROV = "Microsoft Enhanced Cryptographic Provider v1.0"
                $MS_SCARD_PROV = "Microsoft Base Smart Card Crypto Provider"
                $MS_STRONG_PROV = "Microsoft Strong Cryptographic Provider"
    condition:
        any of them
}