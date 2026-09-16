import "pe"
rule SentinelCheckSentinelLicense : SafeNet
{
	meta:
		author="_pusher_"
	condition:
        	pe.exports("CheckSentinelLicense")
}